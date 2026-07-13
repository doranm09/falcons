from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request

STATUS_URL = os.environ.get("HISTORIAN_STATUS_URL", "http://127.0.0.1:4840/")
DESTINATION_HOST = os.environ.get("EXPORT_DESTINATION_HOST", "10.4.50.10")
DESTINATION_PORT = int(os.environ.get("EXPORT_DESTINATION_PORT", "5514"))
INTERVAL_SECONDS = max(float(os.environ.get("EXPORT_INTERVAL_SECONDS", "2")), 0.1)
HTTP_TIMEOUT_SECONDS = max(float(os.environ.get("EXPORT_HTTP_TIMEOUT_SECONDS", "1.5")), 0.1)


def read_historian() -> dict:
    with urllib.request.urlopen(STATUS_URL, timeout=HTTP_TIMEOUT_SECONDS) as response:
        raw = response.read()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("historian status endpoint did not return a JSON object")
    return payload


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    destination = (DESTINATION_HOST, DESTINATION_PORT)
    print(
        f"historian exporter polling {STATUS_URL} and sending to "
        f"{DESTINATION_HOST}:{DESTINATION_PORT}/udp",
        flush=True,
    )

    while True:
        started = time.time()
        try:
            status = read_historian()
            envelope = {
                "schema": "falcons.historian-export.v1",
                "exported_at": time.time(),
                "source_asset": "historian",
                "transport": "one-way-udp",
                "status": status,
            }
            raw = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
            sock.sendto(raw, destination)
            print(f"exported {len(raw)} bytes", flush=True)
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
            print(f"historian export skipped: {exc}", flush=True)

        elapsed = time.time() - started
        time.sleep(max(0.0, INTERVAL_SECONDS - elapsed))


if __name__ == "__main__":
    main()
