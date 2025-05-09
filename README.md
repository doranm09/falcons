# Cybersecurity Digital Twin for Advanced Networked Systems

This project is a full-stack Django platform that simulates and secures networked environments (e.g., advanced reactors or industrial control systems). It integrates passive monitoring, active scanning, vulnerability assessment, and remote agent coordination into a cohesive digital twin.

---

## 🌐 Project Architecture

- **Django + Celery Backend** — Topology modeling, scans, CVE storage
- **Cytoscape.js Frontend** — Visual graph of nodes and link latencies
- **Passive Sniffer API (Flask)** — Starts/stops sniffing via exposed interfaces
- **Host Agent (Python)** — Pushes system info and responds to remote commands
- **Dockerized Infrastructure** — PostgreSQL, Redis, Flask sniffer, Celery worker

---

## 🔒 Key Features

### 🕸 1. Network Mapping & Node Discovery
- Passive sniffer interface management via dashboard
- IP discovery and latency-weighted graph generation
- Dijkstra-based shortest path calculation
- Versioned scans with historical view

### 🛡 2. Vulnerability Assessment
- CVE ingestion from NVD (via keyword or CPE)
- Severity scoring and association with nodes
- Admin integration for search, filter, and review

### 💻 3. Persistent Host Agent
- Periodic system info push (CPU, interfaces, processes)
- Command polling (e.g., test ping, scans)
- Remote execution with output POST-back

### ⚙️ 4. Real-Time Visualization
- Dynamic network graph with Cytoscape.js
- Node color/size/styling mapped to attributes
- Interactive shortest path UI

---

## 🚀 Getting Started

### Prerequisites
- Docker & Docker Compose
- Python 3.10+ (for host agent)

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

## 🧪 Testing Agent Commands

From the Django Admin:
1. Go to **AgentCommand**
2. Create a new entry:
   - `agent_id`: (matches your MAC or UUID)
   - `action`: e.g., `ping` or `scan`
3. Agent will pull command and respond

---

## 📬 API Endpoints (Simplified)

| Endpoint                | Method | Purpose                      |
|-------------------------|--------|------------------------------|
| `/agent/report/`        | POST   | Receive system info from agent |
| `/agent/commands/`      | GET    | Agent polls for commands     |
| `/agent/command_result/`| POST   | Agent returns command output |
| `/sniffer/interfaces/`  | GET    | List interfaces (Flask)      |
| `/sniffer/start/`       | POST   | Start sniffing on interface  |
| `/sniffer/stop/`        | POST   | Stop packet capture          |

---

## 🔧 Tech Stack

- Python 3.10
- Django 3.2+
- Celery + Redis
- PostgreSQL 15+
- Cytoscape.js (frontend graph)
- Flask (sniffer API)
- psutil / platform / requests (host agent)

---

## 📁 Directory Structure

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

## 📜 License

© 2025 Michael Doran — for academic and federal cybersecurity research. Not intended for offensive use without explicit authorization.

---

## 📅 Roadmap
### ✅ Current Functionality
- [x] Task 1.1: Passive Listener to capture real-time traffic
- [x] Task 1.2: Extended Node model with protocols, banners, status
- [x] Task 1.3: Visualize topology as weighted graph (Cytoscape)
- [x] Task 1.4: Versioned rescan support
- [x] Task 2.1: Backend vulnerability scan module stub
- [x] Task 2.3: Node color gradient based on CVE severity

---

### 🔬 In Progress / Research-Driven Tasks
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