#!/usr/bin/env python3
import json
import os
import time
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer

SERVICE_NAME = os.getenv("SERVICE_NAME", "service")
SERVICE_ROLE = os.getenv("SERVICE_ROLE", "generic")
SERVICE_ZONE = os.getenv("SERVICE_ZONE", "unknown")
SERVICE_PORT = int(os.getenv("SERVICE_PORT", "8080"))
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "0.1")
CONFIG_BASELINE = os.getenv("CONFIG_BASELINE", "baseline-v1")
PATCH_LEVEL = os.getenv("PATCH_LEVEL", "2026.01")
PROTOCOL_NAME = os.getenv("PROTOCOL_NAME", "")
PROTOCOL_RATE = os.getenv("PROTOCOL_RATE", "")
AUTH_EVENT_COUNT = os.getenv("AUTH_EVENT_COUNT", "")
LOG_PATH = os.getenv("LOG_PATH", f"/data/{SERVICE_NAME}.log")
FIXED_TIME = os.getenv("FIXED_TIME", "2026-01-25T00:00:00Z")

BASE_CONFIG = {
    "service": SERVICE_NAME,
    "role": SERVICE_ROLE,
    "zone": SERVICE_ZONE,
    "version": SERVICE_VERSION,
    "baseline": CONFIG_BASELINE,
    "patch_level": PATCH_LEVEL,
    "started_at": FIXED_TIME,
}

EVIDENCE = {
    "config": {
        "service": SERVICE_NAME,
        "role": SERVICE_ROLE,
        "zone": SERVICE_ZONE,
        "version": SERVICE_VERSION,
        "baseline": CONFIG_BASELINE,
        "patch_level": PATCH_LEVEL,
    },
    "telemetry": {
        "status": "ok",
        "uptime_s": 0,
        "fixed_time": FIXED_TIME,
    },
}


def _hash_config(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


EVIDENCE["config"]["baseline_hash"] = _hash_config(EVIDENCE["config"])
if PROTOCOL_NAME:
    EVIDENCE["telemetry"]["protocol"] = PROTOCOL_NAME
if PROTOCOL_RATE:
    EVIDENCE["telemetry"]["protocol_rate"] = PROTOCOL_RATE
if AUTH_EVENT_COUNT:
    EVIDENCE["telemetry"]["auth_event_count"] = AUTH_EVENT_COUNT


def write_log(message: str) -> None:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as handle:
        handle.write(message + "\n")


class Handler(BaseHTTPRequestHandler):
    def _send(self, payload, code=200):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        now = int(time.time())
        EVIDENCE["telemetry"]["uptime_s"] = now
        if self.path == "/health":
            self._send({"status": "ok", **BASE_CONFIG})
            return
        if self.path == "/evidence":
            self._send(EVIDENCE)
            return
        if self.path == "/identity":
            self._send(BASE_CONFIG)
            return
        self._send({"error": "not_found"}, code=404)

    def log_message(self, fmt, *args):
        write_log("%s - - [%s] %s" % (self.address_string(), FIXED_TIME, fmt % args))


if __name__ == "__main__":
    write_log(f"{FIXED_TIME} {SERVICE_NAME} started on {SERVICE_PORT}")
    server = HTTPServer(("0.0.0.0", SERVICE_PORT), Handler)
    server.serve_forever()
