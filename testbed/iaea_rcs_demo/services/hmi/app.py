import json
import os
import threading
import time
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from opcua import Client


DEVICE_NAME = os.getenv("DEVICE_NAME", "HMI")
DEVICE_ROLE = os.getenv("DEVICE_ROLE", "Layer2 HMI")
DEVICE_DESC = os.getenv("DEVICE_DESC", "")
HTTP_PORTS = [
    int(item.strip())
    for item in os.getenv("SERVICE_PORTS", "80,443").split(",")
    if item.strip()
]
POLL_INTERVAL_SEC = float(os.getenv("HMI_POLL_INTERVAL_SEC", "1.0"))

BRIDGE_POINTS = [
    "bridge_online",
    "bridge_poll_errors",
    "bridge_last_success_epoch",
]

PLC_POINT_SETS = {
    "main": [
        "pt455_pv",
        "pt455_status",
        "pt456_pv",
        "pt456_status",
        "pt457_pv",
        "pt457_status",
        "average_pressure",
        "health_code",
        "hv_owner",
        "hv_applied",
        "hv_last_writer",
        "hv_status",
        "pvb_owner",
        "pvb_applied",
        "pvb_last_writer",
        "pvb_status",
        "pvc_owner",
        "pvc_applied",
        "pvc_last_writer",
        "pvc_status",
        "heat_owner",
        "heat_applied",
        "heat_last_writer",
        "heat_status",
        "exported_hv_owner",
        "exported_hv_command",
        "exported_pvb_owner",
        "exported_pvb_command",
        "exported_pvc_owner",
        "exported_pvc_command",
        "exported_heat_owner",
        "exported_heat_command",
    ],
    "backup": [
        "pt456_pv",
        "pt456_status",
        "pt457_pv",
        "pt457_status",
        "pt458_pv",
        "pt458_status",
        "average_pressure",
        "health_code",
        "hv_owner",
        "hv_applied",
        "hv_last_writer",
        "hv_status",
        "pvb_owner",
        "pvb_applied",
        "pvb_last_writer",
        "pvb_status",
        "pvc_owner",
        "pvc_applied",
        "pvc_last_writer",
        "pvc_status",
        "heat_owner",
        "heat_applied",
        "heat_last_writer",
        "heat_status",
        "exported_hv_owner",
        "exported_hv_command",
        "exported_pvb_owner",
        "exported_pvb_command",
        "exported_pvc_owner",
        "exported_pvc_command",
        "exported_heat_owner",
        "exported_heat_command",
    ],
}

PLC_CONFIGS = [
    {
        "name": "plc-main",
        "profile": "main",
        "endpoint": os.getenv("PLC_MAIN_OPC_ENDPOINT", "opc.tcp://10.1.1.14:4840/main"),
        "namespace": os.getenv("PLC_MAIN_OPC_NAMESPACE", "urn:iaea-rcs-demo:main"),
    },
    {
        "name": "plc-backup",
        "profile": "backup",
        "endpoint": os.getenv("PLC_BACKUP_OPC_ENDPOINT", "opc.tcp://10.1.2.15:4840/backup"),
        "namespace": os.getenv("PLC_BACKUP_OPC_NAMESPACE", "urn:iaea-rcs-demo:backup"),
    },
]


def epoch_to_text(value):
    if not value:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


class ReusableHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


STATE_LOCK = threading.Lock()
STATE = {
    "device": DEVICE_NAME,
    "role": DEVICE_ROLE,
    "description": DEVICE_DESC,
    "generated_at": 0,
    "plcs": {
        config["name"]: {
            "endpoint": config["endpoint"],
            "namespace": config["namespace"],
            "connected": False,
            "error": "starting",
            "updated_at": 0,
            "values": {},
        }
        for config in PLC_CONFIGS
    },
}


def get_namespace_index(client, namespace_uri):
    namespace_array = client.get_namespace_array()
    for index, value in enumerate(namespace_array):
        if value == namespace_uri:
            return index
    raise RuntimeError(f"namespace not found: {namespace_uri}")


class OpcPoller(threading.Thread):
    def __init__(self, config):
        super().__init__(daemon=True)
        self.name = config["name"]
        self.endpoint = config["endpoint"]
        self.namespace = config["namespace"]
        self.points = PLC_POINT_SETS[config["profile"]] + BRIDGE_POINTS

    def update_state(self, **kwargs):
        with STATE_LOCK:
            plc_state = STATE["plcs"][self.name]
            plc_state.update(kwargs)
            STATE["generated_at"] = time.time()

    def run(self):
        while True:
            client = None
            try:
                client = Client(self.endpoint, timeout=4)
                client.connect()
                namespace_index = get_namespace_index(client, self.namespace)
                nodes = {
                    point: client.get_node(f"ns={namespace_index};s={point}")
                    for point in self.points
                }

                while True:
                    values = {name: node.get_value() for name, node in nodes.items()}
                    self.update_state(
                        connected=True,
                        error="",
                        updated_at=time.time(),
                        values=values,
                    )
                    time.sleep(POLL_INTERVAL_SEC)
            except Exception as exc:
                self.update_state(
                    connected=False,
                    error=str(exc),
                    updated_at=time.time(),
                )
                time.sleep(POLL_INTERVAL_SEC)
            finally:
                if client is not None:
                    try:
                        client.disconnect()
                    except Exception:
                        pass


def snapshot_state():
    with STATE_LOCK:
        return json.loads(json.dumps(STATE))


def render_rows(pairs):
    return "\n".join(
        f"<tr><th>{escape(label)}</th><td>{escape(str(value))}</td></tr>"
        for label, value in pairs
    )


def render_plc_card(name, plc_state):
    values = plc_state.get("values", {})
    sensor_rows = []
    for sensor in (
        "pt455_pv",
        "pt455_status",
        "pt456_pv",
        "pt456_status",
        "pt457_pv",
        "pt457_status",
        "pt458_pv",
        "pt458_status",
    ):
        if sensor in values:
            sensor_rows.append((sensor, values[sensor]))

    summary_rows = [
        ("average_pressure", values.get("average_pressure", "-")),
        ("health_code", values.get("health_code", "-")),
        ("bridge_online", values.get("bridge_online", "-")),
        ("bridge_poll_errors", values.get("bridge_poll_errors", "-")),
        ("bridge_last_success_epoch", epoch_to_text(values.get("bridge_last_success_epoch", 0))),
    ]

    actuator_rows = []
    for prefix in ("hv", "pvb", "pvc", "heat"):
        actuator_rows.append(
            (
                prefix,
                f"owner={values.get(prefix + '_owner', '-')}, "
                f"applied={values.get(prefix + '_applied', '-')}, "
                f"last_writer={values.get(prefix + '_last_writer', '-')}, "
                f"status={values.get(prefix + '_status', '-')}",
            )
        )

    summary_pairs = [
        ("endpoint", plc_state.get("endpoint", "")),
        ("namespace", plc_state.get("namespace", "")),
        ("connected", plc_state.get("connected", False)),
        ("last_update", epoch_to_text(plc_state.get("updated_at", 0))),
    ]
    if plc_state.get("error"):
        summary_pairs.append(("error", plc_state["error"]))

    return f"""
      <section class="card">
        <header class="card-header">
          <div>
            <h2>{escape(name)}</h2>
            <p>{escape('connected' if plc_state.get('connected') else 'disconnected')}</p>
          </div>
        </header>
        <div class="grid">
          <table>
            <caption>Link</caption>
            {render_rows(summary_pairs)}
          </table>
          <table>
            <caption>Sensors</caption>
            {render_rows(sensor_rows or [('status', 'no data')])}
          </table>
          <table>
            <caption>Summary</caption>
            {render_rows(summary_rows)}
          </table>
          <table>
            <caption>Actuators</caption>
            {render_rows(actuator_rows)}
          </table>
        </div>
      </section>
    """


def render_html():
    state = snapshot_state()
    cards = "\n".join(
        render_plc_card(name, plc_state)
        for name, plc_state in state["plcs"].items()
    )
    refreshed = epoch_to_text(state.get("generated_at", 0))
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="2">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{escape(DEVICE_NAME)} OPC Dashboard</title>
    <style>
      :root {{
        --bg: #0d1b2a;
        --panel: #10253a;
        --panel-alt: #17314c;
        --ink: #e0ecf7;
        --muted: #9fbed8;
        --accent: #3cc2a2;
        --line: rgba(224, 236, 247, 0.14);
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
        color: var(--ink);
        background:
          radial-gradient(circle at top right, rgba(60, 194, 162, 0.18), transparent 28rem),
          linear-gradient(180deg, #09131d 0%, var(--bg) 100%);
      }}
      main {{
        max-width: 1200px;
        margin: 0 auto;
        padding: 2rem 1.25rem 3rem;
      }}
      .hero {{
        display: flex;
        justify-content: space-between;
        align-items: end;
        gap: 1rem;
        margin-bottom: 1.5rem;
      }}
      h1 {{
        margin: 0 0 0.35rem;
        font-size: clamp(2rem, 4vw, 3.2rem);
        letter-spacing: 0.04em;
        text-transform: uppercase;
      }}
      p {{
        margin: 0;
        color: var(--muted);
      }}
      .stack {{
        display: grid;
        gap: 1rem;
      }}
      .card {{
        background: linear-gradient(180deg, rgba(23, 49, 76, 0.96), rgba(16, 37, 58, 0.96));
        border: 1px solid var(--line);
        border-radius: 1.2rem;
        padding: 1rem;
        box-shadow: 0 20px 50px rgba(0, 0, 0, 0.25);
      }}
      .card-header {{
        display: flex;
        justify-content: space-between;
        align-items: baseline;
        margin-bottom: 1rem;
      }}
      .card-header h2 {{
        margin: 0;
        font-size: 1.2rem;
      }}
      .grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
        gap: 0.9rem;
      }}
      table {{
        width: 100%;
        border-collapse: collapse;
        background: rgba(9, 19, 29, 0.42);
        border-radius: 0.9rem;
        overflow: hidden;
      }}
      caption {{
        text-align: left;
        padding: 0.8rem 0.9rem 0.45rem;
        color: var(--accent);
        font-weight: 700;
        letter-spacing: 0.03em;
      }}
      th, td {{
        text-align: left;
        padding: 0.55rem 0.9rem;
        border-top: 1px solid var(--line);
        vertical-align: top;
      }}
      th {{
        width: 45%;
        color: var(--muted);
        font-weight: 600;
      }}
      td {{
        font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
      }}
      @media (max-width: 700px) {{
        .hero {{ align-items: start; flex-direction: column; }}
      }}
    </style>
  </head>
  <body>
    <main>
      <section class="hero">
        <div>
          <p>{escape(DEVICE_ROLE)}</p>
          <h1>{escape(DEVICE_NAME)}</h1>
          <p>{escape(DEVICE_DESC)}</p>
        </div>
        <p>Last refresh: {escape(refreshed)}</p>
      </section>
      <section class="stack">
        {cards}
      </section>
    </main>
  </body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def respond(self, code, body, content_type):
        payload = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/api/state":
            self.respond(200, json.dumps(snapshot_state(), indent=2), "application/json")
            return
        self.respond(200, render_html(), "text/html; charset=utf-8")


if __name__ == "__main__":
    for config in PLC_CONFIGS:
        OpcPoller(config).start()

    for port in HTTP_PORTS:
        server = ReusableHTTPServer(("0.0.0.0", port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    print(f"{DEVICE_NAME} listening on ports: {', '.join(str(port) for port in HTTP_PORTS)}", flush=True)
    threading.Event().wait()
