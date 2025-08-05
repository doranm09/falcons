# Sniffer + Agent API Service

This is a lightweight Flask-based backend for:

- Controlling a live packet capture interface
- Accepting agent heartbeats and SBOM data
- Returning commands to agents
- Logging all network events to a file and console

## Requirements

- Python 3.8+
- `Flask`
- `pyshark`
- `netifaces`

Install with:

```bash
pip install flask pyshark netifaces
```

## Usage

Run the service:

```bash
python sniffer_server.py
```

This will:
- Start the Flask app on `http://localhost:5000`
- Write logs to `./logs/sniffer.log`

## API Endpoints

### `/start` `POST`

Start packet capture on a given interface.

**Request JSON:**
```json
{
  "interface": "eth0"
}
```

**Response:**
```json
{
  "status": "started",
  "interface": "eth0"
}
```

---

### `/stop` `POST`

Stop the running capture session.

**Response (when active):**
```json
{ "status": "stopping" }
```

---

### `/interfaces` `GET`

List available network interfaces.

**Response:**
```json
{ "interfaces": ["eth0", "lo", "wlan0"] }
```

---

### `/sbom` `POST`

Receive a Software Bill of Materials (SBOM) from an agent.

**Headers:**
- `X-Agent-ID`: Unique ID of the agent
- `X-Timestamp`: ISO 8601 timestamp

**Body:** (CycloneDX JSON or raw package list)

SBOMs are saved as `/tmp/received_sbom_<agent_id>.json`.

---

### `/agent/report/` `POST`

Receive a heartbeat from an agent.

**Body:** JSON object of system info.

**Response:**
```json
{ "status": "ok" }
```

---

### `/agent/commands/` `GET`

Return a list of commands for a specific agent.

**Query param:** `?agent_id=<uuid>`

**Response:**
```json
{ "commands": [] }
```

_(You can modify this to return dynamic commands.)_

---

### `/agent/command_result/` `POST`

Accept and log results from a command previously issued to an agent.

**Response:**
```json
{ "status": "acknowledged" }
```

---

## Internal Behavior

- Uses `pyshark.LiveCapture` to sniff packets
- Logs to both stdout and `./logs/sniffer.log`
- Interface state (`listener_active`) is managed via global flag
- Multi-threaded with Flask + background capture thread

---

## 🗃 File Output

- SBOMs are saved in `/tmp/received_sbom_<agent_id>.json`
- Logs are written to `./logs/sniffer.log`