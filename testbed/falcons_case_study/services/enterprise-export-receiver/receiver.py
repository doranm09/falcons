from __future__ import annotations

import json
import os
import socket
import time
from pathlib import Path
from typing import Any

BIND_HOST = os.environ.get("EXPORT_BIND_HOST", "0.0.0.0")
PORT = int(os.environ.get("EXPORT_PORT", "5514"))
LOG_PATH = Path(os.environ.get("EXPORT_LOG", "/data/historian-export.jsonl"))
MAX_DATAGRAM = int(os.environ.get("EXPORT_MAX_DATAGRAM_BYTES", "65535"))


def _decode_payload(raw: bytes) -> Any:
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}


def main() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((BIND_HOST, PORT))
    print(f"enterprise historian-export receiver listening on {BIND_HOST}:{PORT}/udp", flush=True)

    while True:
        raw, source = sock.recvfrom(MAX_DATAGRAM)
        record = {
            "received_at": time.time(),
            "source_ip": source[0],
            "source_port": source[1],
            "payload": _decode_payload(raw),
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        print(line, flush=True)


if __name__ == "__main__":
    main()
