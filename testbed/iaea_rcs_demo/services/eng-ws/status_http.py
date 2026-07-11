import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


DEVICE_NAME = os.getenv("DEVICE_NAME", "Engineer-Workstation")
DEVICE_ROLE = os.getenv("DEVICE_ROLE", "Layer2 engineering workstation")
DEVICE_DESC = os.getenv("DEVICE_DESC", "")
NO_VNC_PORT = int(os.getenv("ENGINEER_WS_NOVNC_PORT", "6080"))
VNC_PASSWORD = os.getenv("ENGINEER_WS_VNC_PASSWORD", "engwsdemo")
HTTP_PORTS = [
    int(item.strip())
    for item in os.getenv("SERVICE_PORTS", "80,443").split(",")
    if item.strip()
]


class ReusableHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def payload():
    return {
        "device": DEVICE_NAME,
        "role": DEVICE_ROLE,
        "description": DEVICE_DESC,
        "status": "ok",
        "usage": [
            "docker exec -it engineer-ws bash",
            "opc-read opc.tcp://10.1.13.10:4840/main --namespace urn:iaea-rcs-demo:main",
            "opc-read opc.tcp://10.2.23.10:4840/backup --namespace urn:iaea-rcs-demo:backup",
            f"Open http://127.0.0.1:{NO_VNC_PORT}/vnc.html and enter the VNC password",
        ],
        "tools": [
            "curl",
            "designerlauncher",
            "ip",
            "nc",
            "opc-read",
            "ping",
            "tcpdump",
        ],
        "desktop": {
            "novnc": f"http://127.0.0.1:{NO_VNC_PORT}/vnc.html",
            "vnc_password": VNC_PASSWORD,
        },
    }


def render_html():
    return """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Engineer Workstation</title>
    <style>
      :root {
        --bg: #10161f;
        --panel: #18222f;
        --ink: #eef4fb;
        --muted: #9cb0c4;
        --accent: #ffb347;
      }
      body {
        margin: 0;
        font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
        background: linear-gradient(160deg, #0c1118, var(--bg));
        color: var(--ink);
      }
      main {
        max-width: 900px;
        margin: 0 auto;
        padding: 2rem 1.25rem 3rem;
      }
      .card {
        background: var(--panel);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 1rem;
        padding: 1.25rem;
      }
      h1 {
        margin: 0 0 0.4rem;
        font-size: clamp(2rem, 4vw, 3rem);
      }
      p, li {
        color: var(--muted);
      }
      code {
        color: var(--accent);
        font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
      }
    </style>
  </head>
  <body>
    <main>
      <section class="card">
        <h1>Engineer Workstation</h1>
        <p>Ubuntu-based Layer 2 engineering node with OPC and network tooling.</p>
        <p>Open a shell with <code>docker exec -it engineer-ws bash</code>.</p>
        <p>Remote desktop: <code>http://127.0.0.1:%d/vnc.html</code> with password <code>%s</code>.</p>
        <p>The desktop opens a Layer 2 shell for manual OPC, route, and packet-capture checks.</p>
        <ul>
          <li><code>opc-read opc.tcp://10.1.13.10:4840/main --namespace urn:iaea-rcs-demo:main</code></li>
          <li><code>opc-read opc.tcp://10.2.23.10:4840/backup --namespace urn:iaea-rcs-demo:backup</code></li>
          <li><code>tcpdump -i eth0 -nn tcp port 4840</code></li>
        </ul>
      </section>
    </main>
  </body>
</html>
""" % (NO_VNC_PORT, VNC_PASSWORD)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def _write(self, code, body, content_type):
        payload_bytes = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload_bytes)))
        self.end_headers()
        self.wfile.write(payload_bytes)

    def do_GET(self):
        if self.path == "/api/status":
            self._write(200, json.dumps(payload(), indent=2), "application/json")
            return
        self._write(200, render_html(), "text/html; charset=utf-8")


if __name__ == "__main__":
    for port in HTTP_PORTS:
        server = ReusableHTTPServer(("0.0.0.0", port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    print(f"{DEVICE_NAME} listening on ports: {', '.join(str(port) for port in HTTP_PORTS)}", flush=True)
    threading.Event().wait()
