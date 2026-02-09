# Host Agent

This Python-based host agent monitors system information, collects SBOM data, passively sniffs network packets, and dynamically maps latency between network nodes using a Dijkstra-based shortest path algorithm.

## Requirements

- Python 3.8+
- `psutil`
- `requests`
- `scapy`
- `argparse`
- `sbom` module with:
  - `collect_packages()`
  - `generate_cyclonedx_sbom()`

Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

Install requirements:

```bash
pip install -r requirements.txt
```

## CLI Usage

```bash
python agent.py <command> [options]
```

### Commands

| Command       | Description                                                  |
|---------------|--------------------------------------------------------------|
| `run`         | Run persistent loop (heartbeat + polling)                    |
| `heartbeat`   | Send a one-time heartbeat                                    |
| `poll`        | Poll for commands from the server and handle responses       |
| `info`        | Print system info (hardware, interfaces, processes, etc.)    |
| `sbom`        | Generate SBOM and send it to the server                      |
| `sniff`       | Start packet capture on a specific interface                 |
| `path`        | Interactively compute shortest path between IPs using RTT    |
| `cyber`       | Collect cyber template data (OS, libraries, MAC addresses, ports) |

## Capabilities

### System Monitoring

Each heartbeat (`/agent/report/`) includes:

- Hostname
- OS/Platform info
- CPU & Memory stats
- Network interfaces (IP/MAC)
- Running processes

### SBOM Collection

```bash
python agent.py sbom --format cyclonedx --output sbom.json
```

- Formats: `raw` (default) or `cyclonedx`
- Automatically POSTs SBOM to `/sbom` on the sniffer server
- Optional: attach vulnerability output (e.g., Grype/Trivy JSON):

```bash
python agent.py sbom --format cyclonedx --output sbom.json --vuln-file grype.json
```

Analyzing `cyclonedx` formatted SBOM with `trivvy`

```bash
trivy sbom <path to sbom.json>
```

You should see output like the following:

```
│          Library           │  Vulnerability   │ Severity │  Status  │        Installed Version         │ Fixed Version │                            Title                             │
├────────────────────────────┼──────────────────┼──────────┼──────────┼──────────────────────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ amd64-microcode            │ CVE-2021-26318   │ MEDIUM   │ affected │ 3.20250311.1ubuntu0.24.04.1      │               │ A timing and power-based side channel attack leveraging the  │
│                            │                  │          │          │                                  │               │ x86 PREFETCH instructions...                                 │
│                            │                  │          │          │                                  │               │ https://avd.aquasec.com/nvd/cve-2021-26318                   │
│                            ├──────────────────┤          │          │                                  ├───────────────┼──────────────────────────────────────────────────────────────┤
│                            │ CVE-2024-36350   │          │          │                                  │               │ kernel: information leak via transient execution             │
│                            │                  │          │          │                                  │               │ vulnerability in some AMD processors                         │
│                            │                  │          │          │                                  │               │ https://avd.aquasec.com/nvd/cve-2024-36350                   │
│                            ├──────────────────┤          │          │                                  ├───────────────┼──────────────────────────────────────────────────────────────┤
│                            │ CVE-2024-36357   │          │          │                                  │               │ kernel: transient execution vulnerability in some AMD        │
│                            │                  │          │          │                                  │               │ processors                                                   │
│                            │                  │          │          │                                  │               │ https://avd.aquasec.com/nvd/cve-2024-36357                   │
│                            ├──────────────────┼──────────┤          │                                  ├───────────────┼──────────────────────────────────────────────────────────────┤
│                            │ CVE-2024-36348   │ LOW      │          │                                  │               │ A transient execution vulnerability in some AMD processors   │
│                            │                  │          │          │                                  │               │ may allow a ......                                           │
│                            │                  │          │          │                                  │               │ https://avd.aquasec.com/nvd/cve-2024-36348                   │
│                            ├──────────────────┤          │          │                                  ├───────────────┼──────────────────────────────────────────────────────────────┤
│                            │ CVE-2024-36349   │          │          │                                  │               │ A transient execution vulnerability in some AMD processors   │
│                            │                  │          │          │                                  │               │ may allow a ......                                           │
│                            │                  │          │          │                                  │               │ https://avd.aquasec.com/nvd/cve-2024-36349                   │

``` 

### Passive Sniffing & Discovery

```bash
python agent.py sniff --interface eth0
```

This will:
- Detect neighbor IP/MACs via ARP, TCP, ICMP, UDP
- Record connection latencies using TCP SYN/SYN-ACK delta
- Update a dynamic network graph in memory

Example log:
```
[latency] 10.0.0.1 -> 10.0.0.2: ~1.50 ms
[neighbor] new: 10.0.0.2 / aa:bb:cc:dd via TCP
```

### Shortest Path Analysis

```bash
python agent.py path
```

Provides Dijkstra-based shortest path (RTT-optimized) between known hosts:

```
Enter start IP: 10.0.0.1
Enter end IP: 10.0.0.5
[path] 10.0.0.1 -> 10.0.0.5 in 4.32 ms via: 10.0.0.1 -> 10.0.0.3 -> 10.0.0.5
```

### Cyber Template Data Collection

```bash
python agent.py cyber --format template --output cyber_data.json
```

Collects system data specifically formatted for cyber security testing templates:

**OS Information**: Detailed operating system information (e.g., "Ubuntu 24.04.2 LTS")
**Libraries**: Installed packages and libraries from SBOM data (first 50 packages)
**MAC Addresses**: All network interface MAC addresses
**Active Ports**: Currently listening and established network connections

**Output Formats**:
- `template` (default): Just the 4 cyber template fields (OS, lib, MAC, port)
- `full`: Includes additional system information and collection timestamp

**Example Output**:
```json
{
  "OS": "Ubuntu 24.04.2 LTS 24.04.2 LTS (Noble Numbat)",
  "lib": ["package1@1.0.0", "package2@2.1.0", ...],
  "MAC": ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ...],
  "port": [
    {"id": "192.168.1.1:8080", "Protocol": "TCP"},
    {"id": "192.168.1.1:443", "Protocol": "TCP"}
  ]
}
```

## Server Endpoints

Default `SERVER_URL = http://localhost:8000`

Agent communicates with:

- `/agent/report/` — heartbeat POST
- `/agent/commands/?agent_id=...` — poll GET
- `/agent/command_result/` — result POST
- `/sbom` — SBOM data POST (headers: `X-Agent-ID`, `X-Timestamp`)

## Output

- SBOMs: printed or saved to file via `--output`
- Latency graph: in-memory structure updated live
- Sniffer logs: printed to console

## Example

```bash
python agent.py run
# sends heartbeat every 30s and polls for commands
```

```bash
python agent.py sniff --interface eth0
# starts passive traffic listener
```

```bash
python agent.py path
# shortest latency path between nodes
```

```bash
python agent.py cyber --format template --output cyber_data.json
# collect cyber template data for penetration testing
```
