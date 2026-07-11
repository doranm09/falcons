import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread

from modbus_tcp import build_device_model_from_env, start_modbus_server

NAME = os.getenv("DEVICE_NAME", "endpoint")
ROLE = os.getenv("DEVICE_ROLE", "generic")
DESC = os.getenv("DEVICE_DESC", "")
SECONDARY = [x.strip() for x in os.getenv("SECONDARY_IPS", "").split(",") if x.strip()]


def parse_ports(*values):
    ports = set()
    for value in values:
        for item in value.split(","):
            item = item.strip()
            if item:
                ports.add(int(item))
    return sorted(ports)


MODBUS_PORTS = parse_ports(
    os.getenv("MODBUS_PORT", ""),
)

HTTP_PORTS = [
    port
    for port in parse_ports(
    os.getenv("HTTP_PORT", ""),
    os.getenv("SERVICE_PORTS", ""),
    os.getenv("EXTRA_LISTEN_PORTS", ""),
    )
    if port not in MODBUS_PORTS
]

if not HTTP_PORTS and not MODBUS_PORTS:
    raise RuntimeError("No HTTP or Modbus listen ports configured")


class EndpointServer(ThreadingHTTPServer):
    allow_reuse_address = True

class Handler(BaseHTTPRequestHandler):
    def _write(self, code, payload):
        body = json.dumps(payload, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return

    def do_GET(self):
        payload = {
            "device": NAME,
            "role": ROLE,
            "description": DESC,
            "path": self.path,
            "secondary_ips": SECONDARY,
            "listen_ports": HTTP_PORTS + MODBUS_PORTS,
            "local_port": self.server.server_port,
            "hostname": os.uname().nodename,
            "status": "ok",
        }
        self._write(200, payload)

if __name__ == "__main__":
    servers = []
    for port in HTTP_PORTS:
        server = EndpointServer(("0.0.0.0", port), Handler)
        servers.append(server)
        Thread(target=server.serve_forever, daemon=True).start()

    modbus_servers = []
    if MODBUS_PORTS:
        model = build_device_model_from_env()
        for port in MODBUS_PORTS:
            modbus_servers.append(start_modbus_server(model, port))

    print(
        f"{NAME} listening on ports: "
        f"{', '.join(str(port) for port in (HTTP_PORTS + MODBUS_PORTS))}",
        flush=True,
    )
    Event().wait()
