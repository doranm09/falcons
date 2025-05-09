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

## 🧠 Roadmap (in progress)

- [x] Passive sniffer interface via Flask
- [x] Host agent with persistent command polling
- [x] NVD integration via keyword
- [ ] CPE-to-node fingerprinting
- [ ] OpenVAS/Greenbone plugin integration
- [ ] Regulatory CDA tier export + diff

---

## 🙋‍♂️ Questions?

Open an issue or contact via GitHub or LinkedIn. This work is under development as part of a doctoral research effort into cyber-informed engineering and digital twin resilience.